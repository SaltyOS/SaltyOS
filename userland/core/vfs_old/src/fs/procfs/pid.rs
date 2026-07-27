// SPDX-License-Identifier: GPL-2.0-only
//! Per-process /proc/<pid>/ IPC queries and content generators.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::posix::mmsrv::*;
use trona_protocol::posix::procmgr::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::fs::metrics::{PerPidMemSnapshot, per_pid_mem_snapshot};
use crate::server::consts::*;

// uapi: landing in parallel — VMA listing from mmsrv
const MM_LIST_VMAS_LABEL: u64 = 0xA8;

use super::generators::{fmt_u32, fmt_u64, fmt_u64_hex};

/// Get the IPC context.
#[inline]
fn ipc_ctx() -> *mut IpcContext {
    crate::ipc_ctx()
}

/// Query procmgr for list of PIDs. Returns count (up to 19).
pub(super) unsafe fn proc_list_pids(pids: &mut [u32; 19]) -> usize {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_LIST_PIDS;
        msg.length = 0;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }
        let count = reply.regs[19] as usize;
        let n = if count > 19 { 19 } else { count };
        for i in 0..n {
            pids[i] = reply.regs[i] as u32;
        }
        n
    }
}

/// Query procmgr for process info. Returns true on success.
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
        msg.label = PM_GET_PROC_INFO;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
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

/// Query procmgr for a process's exe path. Returns byte length on success.
pub(super) unsafe fn proc_get_exe_path(
    pid: u32,
    exe_path: &mut [u8; MAX_PATH_LEN],
) -> Option<usize> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_EXE_PATH;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        let path_len = reply.regs[0] as usize;
        if path_len == 0 || path_len > exe_path.len() {
            return None;
        }
        let src = &reply.regs[1] as *const u64 as *const u8;
        for i in 0..path_len {
            exe_path[i] = *src.add(i);
        }
        Some(path_len)
    }
}

/// Fetch per-process memory stats via the metrics layer. Returns true on success.
///
/// Kept for callers that pre-date the snapshot API; delegates to
/// `per_pid_mem_snapshot` and unpacks the fields they need.
pub(super) unsafe fn proc_get_mem_stats(
    pid: u32,
    heap_base: &mut u64,
    heap_current: &mut u64,
    region_count: &mut u64,
    total_pages: &mut u64,
) -> bool {
    match per_pid_mem_snapshot(pid) {
        Ok(s) => {
            *heap_base = s.heap_base;
            *heap_current = s.heap_current;
            *region_count = s.region_count as u64;
            *total_pages = s.vm_resident_pages;
            true
        }
        Err(_) => false,
    }
}

/// Check whether a PID exists by querying procmgr.
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

/// Generate /proc/<pid>/status content. Returns bytes written.
pub(super) unsafe fn proc_gen_status(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        let mut start_time_ns: u64 = 0;
        let mut _tty_dev: u64 = 0;
        let mut _tty_pgrp: u32 = 0;
        if !proc_get_info(
            pid,
            &mut ppid,
            &mut pgid,
            &mut sid,
            &mut state,
            &mut name,
            &mut start_time_ns,
            &mut _tty_dev,
            &mut _tty_pgrp,
        ) {
            return 0;
        }
        let _ = start_time_ns;

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

        // "Name:\t<name>\n"
        let hdr = b"Name:\t";
        for b in hdr {
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

        // "State:\t<R/Z/T>\n"
        let hdr = b"State:\t";
        for b in hdr {
            if pos < buf_size {
                *dst.add(pos) = *b;
                pos += 1;
            }
        }
        let st_char = match state {
            1 => b'R',
            2 => b'Z',
            3 => b'T',
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

        // "Pid:\t<pid>\n"
        let hdr = b"Pid:\t";
        for b in hdr {
            if pos < buf_size {
                *dst.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(pid, &mut tmp);
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

        // "PPid:\t<ppid>\n"
        let hdr = b"PPid:\t";
        for b in hdr {
            if pos < buf_size {
                *dst.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(ppid, &mut tmp);
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

        // "Pgid:\t<pgid>\n"
        let hdr = b"Pgid:\t";
        for b in hdr {
            if pos < buf_size {
                *dst.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(pgid, &mut tmp);
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

        // "Sid:\t<sid>\n"
        let hdr = b"Sid:\t";
        for b in hdr {
            if pos < buf_size {
                *dst.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(sid, &mut tmp);
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

        let pt = crate::fs::metrics::proc_times(pid).unwrap_or_default();
        let threads = if pt.num_threads == 0 {
            1
        } else {
            pt.num_threads
        };
        let snap = per_pid_mem_snapshot(pid).unwrap_or_default();

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

/// Helper: append `"<label><value>\n"` (u32).
unsafe fn append_kv_u32(buf: &mut [u8], pos: &mut usize, label: &[u8], value: u32) {
    super::generators::append_bytes(buf, pos, label);
    super::generators::append_u32_dec(buf, pos, value);
    super::generators::append_bytes(buf, pos, b"\n");
}

/// Helper: append `"<label><value> kB\n"`.
unsafe fn append_kv_kb(buf: &mut [u8], pos: &mut usize, label: &[u8], kb: u64) {
    super::generators::append_bytes(buf, pos, label);
    super::generators::append_u64_dec(buf, pos, kb);
    super::generators::append_bytes(buf, pos, b" kB\n");
}

/// Append `"<label> <kb> kB\n"` to buf — used by proc_gen_smaps.
fn smaps_emit_kb(buf: &mut [u8], pos: &mut usize, label: &[u8], kb: u64) {
    super::generators::append_bytes(buf, pos, label);
    super::generators::append_bytes(buf, pos, b" ");
    super::generators::append_u64_dec(buf, pos, kb);
    super::generators::append_bytes(buf, pos, b" kB\n");
}

/// Generate /proc/<pid>/stat content (single-line). Returns bytes written.
pub(super) unsafe fn proc_gen_stat(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        let mut start_time_ns: u64 = 0;
        let mut tty_dev: u64 = 0;
        let mut tty_pgrp: u32 = 0;
        if !proc_get_info(
            pid,
            &mut ppid,
            &mut pgid,
            &mut sid,
            &mut state,
            &mut name,
            &mut start_time_ns,
            &mut tty_dev,
            &mut tty_pgrp,
        ) {
            return 0;
        }

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

        // "<pid> (<name>) <state> <ppid> <pgid> <sid> ..."
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
        let st_char = match state {
            1 => b'R',
            2 => b'Z',
            3 => b'T',
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
        let n = fmt_u32(ppid, &mut tmp);
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
        let n = fmt_u32(pgid, &mut tmp);
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
        let n = fmt_u32(sid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *dst.add(pos) = tmp[i];
                pos += 1;
            }
        }
        let ticks_per_sec = TICKS_PER_SEC;
        let start_ticks = start_time_ns.saturating_mul(ticks_per_sec) / 1_000_000_000;
        // CPU runtime + thread count from procmgr. Convert runtime back to
        // Linux-style ticks for `/proc/<pid>/stat`; zeros on IPC failure keep
        // the line syntactically valid for early-boot readers.
        let pt = crate::fs::metrics::proc_times(pid).unwrap_or_default();
        let num_threads = if pt.num_threads == 0 {
            1
        } else {
            pt.num_threads as u64
        };
        let extra_fields: [u64; 16] = [
            tty_dev,         // tty_nr
            tty_pgrp as u64, // tpgid
            0,               // flags
            0,               // minflt
            0,               // cminflt
            0,               // majflt
            0,               // cmajflt
            (((pt.user_time_ns as u128).saturating_mul(ticks_per_sec as u128)) / 1_000_000_000u128)
                as u64, // utime
            (((pt.system_time_ns as u128).saturating_mul(ticks_per_sec as u128))
                / 1_000_000_000u128) as u64, // stime
            0,               // cutime
            0,               // cstime
            0,               // priority
            0,               // nice
            num_threads,     // num_threads
            0,               // itrealvalue
            start_ticks,
        ];
        for field in extra_fields {
            if pos < buf_size {
                *dst.add(pos) = b' ';
                pos += 1;
            }
            let mut tmp64 = [0u8; 20];
            let n = fmt_u64(field, &mut tmp64);
            for i in 0..n {
                if pos < buf_size {
                    *dst.add(pos) = tmp64[i];
                    pos += 1;
                }
            }
        }

        // Fields 23 (vsize in bytes) and 24 (rss in pages) from the snapshot.
        let snap = per_pid_mem_snapshot(pid).unwrap_or_default();
        for field in [snap.vm_reserved_bytes, snap.vm_resident_pages] {
            if pos < buf_size {
                *dst.add(pos) = b' ';
                pos += 1;
            }
            let mut tmp64 = [0u8; 20];
            let n = fmt_u64(field, &mut tmp64);
            for i in 0..n {
                if pos < buf_size {
                    *dst.add(pos) = tmp64[i];
                    pos += 1;
                }
            }
        }

        if pos < buf_size {
            *dst.add(pos) = b'\n';
            pos += 1;
        }

        pos
    }
}

/// Layout of one entry returned by `MM_LIST_VMAS` in the IPC buffer reserved area.
/// 64 bytes, `#[repr(C)]`, matches `MmsrvVmaEntry` in the mmsrv contract.
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

/// Generate /proc/<pid>/maps content. Returns bytes written.
///
/// Format per VMA: `<base>-<end> <prot> 00000000 00:00 0 <region_type>\n`
/// Offset and device/inode are zeroed (no file-backed inode identity yet).
pub(super) unsafe fn proc_gen_maps(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        let ctx = ipc_ctx();
        if (*ctx).ipc_buffer.is_null() {
            return 0;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_LIST_VMAS_LABEL;
        msg.length = 2;
        msg.regs[0] = pid as u64;
        msg.regs[1] = 0; // offset=0 (first page of entries)
        let err = ipc::call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }
        let entry_count = reply.regs[0] as usize;
        let reserved_ptr = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8;

        let entry_size = core::mem::size_of::<VmaEntry>(); // 48
        let max_entries = (IPC_BUFFER_RESERVED_BYTES) / entry_size;
        let count = entry_count.min(max_entries);

        let mut pos = 0usize;
        let mut tmp = [0u8; 20];

        for i in 0..count {
            let entry_ptr = reserved_ptr.add(i * entry_size) as *const VmaEntry;
            let e = &*entry_ptr;
            let end = e.base.wrapping_add(e.length);

            // base-end
            let n = fmt_u64_hex(e.base, &mut tmp);
            super::generators::append_bytes(buf, &mut pos, &tmp[..n]);
            super::generators::append_bytes(buf, &mut pos, b"-");
            let n = fmt_u64_hex(end, &mut tmp);
            super::generators::append_bytes(buf, &mut pos, &tmp[..n]);
            super::generators::append_bytes(buf, &mut pos, b" ");

            // prot string: rwxp / r--p / etc.
            let prot = e.prot;
            let r = if prot & 1 != 0 { b'r' } else { b'-' };
            let w = if prot & 2 != 0 { b'w' } else { b'-' };
            let x = if prot & 4 != 0 { b'x' } else { b'-' };
            super::generators::append_bytes(buf, &mut pos, &[r, w, x, b'p']);
            super::generators::append_bytes(buf, &mut pos, b" 00000000 00:00 0 ");

            // region type as ASCII name
            let region_name: &[u8] = match e.region_type {
                0 => b"[heap]",
                7 => b"[stack]",
                _ => b"",
            };
            super::generators::append_bytes(buf, &mut pos, region_name);
            super::generators::append_bytes(buf, &mut pos, b"\n");
        }
        pos
    }
}

/// Generate /proc/<pid>/cmdline content. Returns bytes written.
/// For now returns the process name (null-terminated).
pub(super) unsafe fn proc_gen_cmdline(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        let mut start_time_ns: u64 = 0;
        let mut tty_dev: u64 = 0;
        let mut tty_pgrp: u32 = 0;
        if !proc_get_info(
            pid,
            &mut ppid,
            &mut pgid,
            &mut sid,
            &mut state,
            &mut name,
            &mut start_time_ns,
            &mut tty_dev,
            &mut tty_pgrp,
        ) {
            return 0;
        }

        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 {
            name_len += 1;
        }
        let copy = if name_len < buf.len() {
            name_len
        } else {
            buf.len().saturating_sub(1)
        };
        for i in 0..copy {
            buf[i] = name[i];
        }
        // cmdline is null-terminated
        if copy < buf.len() {
            buf[copy] = 0;
            copy + 1
        } else {
            copy
        }
    }
}

/// Generate /proc/<pid>/comm content. Returns bytes written.
/// Single line: process name + newline.
pub(super) unsafe fn proc_gen_comm(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        let mut start_time_ns: u64 = 0;
        let mut tty_dev: u64 = 0;
        let mut tty_pgrp: u32 = 0;
        if !proc_get_info(
            pid,
            &mut ppid,
            &mut pgid,
            &mut sid,
            &mut state,
            &mut name,
            &mut start_time_ns,
            &mut tty_dev,
            &mut tty_pgrp,
        ) {
            return 0;
        }

        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 {
            name_len += 1;
        }
        if name_len == 0 {
            return 0;
        }
        let max = buf.len().saturating_sub(1); // reserve for newline
        let copy = if name_len < max { name_len } else { max };
        for i in 0..copy {
            buf[i] = name[i];
        }
        if copy < buf.len() {
            buf[copy] = b'\n';
            copy + 1
        } else {
            copy
        }
    }
}

/// Generate /proc/<pid>/statm content. Returns bytes written.
///
/// Format (space-separated, pages): `size resident shared text lib data dt`.
pub(super) unsafe fn proc_gen_statm(pid: u32, buf: &mut [u8]) -> usize {
    let snap = match per_pid_mem_snapshot(pid) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let page_sz: u64 = 4096;
    let size = snap.vm_reserved_bytes / page_sz;
    let resident = snap.vm_resident_pages;
    // approximation: per-page mapcount not exposed by kernel
    let shared = snap.vm_shared_pages;
    let text = snap.vm_exe_bytes / page_sz;
    let lib = snap.vm_lib_bytes / page_sz;
    let data = snap.vm_data_bytes / page_sz;

    let mut pos = 0usize;
    let g = super::generators::append_u64_dec;
    g(buf, &mut pos, size);
    super::generators::append_bytes(buf, &mut pos, b" ");
    g(buf, &mut pos, resident);
    super::generators::append_bytes(buf, &mut pos, b" ");
    g(buf, &mut pos, shared);
    super::generators::append_bytes(buf, &mut pos, b" ");
    g(buf, &mut pos, text);
    super::generators::append_bytes(buf, &mut pos, b" ");
    g(buf, &mut pos, lib);
    super::generators::append_bytes(buf, &mut pos, b" ");
    g(buf, &mut pos, data);
    super::generators::append_bytes(buf, &mut pos, b" 0\n"); // dt always 0
    pos
}

/// Generate /proc/<pid>/io content — per-process I/O counters.
///
/// All fields are 0 until I/O accounting lands.
pub(super) unsafe fn proc_gen_io(_pid: u32, buf: &mut [u8]) -> usize {
    const BODY: &[u8] = b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n";
    let n = BODY.len().min(buf.len());
    buf[..n].copy_from_slice(&BODY[..n]);
    n
}

/// Generate /proc/<pid>/smaps content. Returns bytes written.
///
/// Walks VMA entries from `MM_LIST_VMAS` and emits one block per entry with
/// Size, Rss, Pss (approximation), Shared_Clean/Dirty, Private_Clean/Dirty,
/// Referenced, Anonymous, Swap, KernelPageSize, MMUPageSize, Locked.
pub(super) unsafe fn proc_gen_smaps(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        let ctx = ipc_ctx();
        if (*ctx).ipc_buffer.is_null() {
            return 0;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_LIST_VMAS_LABEL;
        msg.length = 2;
        msg.regs[0] = pid as u64;
        msg.regs[1] = 0;
        let err = ipc::call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }
        let entry_count = reply.regs[0] as usize;
        let reserved_ptr = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8;

        let entry_size = core::mem::size_of::<VmaEntry>();
        let max_entries = IPC_BUFFER_RESERVED_BYTES / entry_size;
        let count = entry_count.min(max_entries);

        let page_sz_kb: u64 = 4; // 4096 / 1024

        let mut pos = 0usize;
        let mut tmp = [0u8; 20];

        for i in 0..count {
            let entry_ptr = reserved_ptr.add(i * entry_size) as *const VmaEntry;
            let e = &*entry_ptr;
            let end = e.base.wrapping_add(e.length);

            // Header line: base-end prot 00000000 00:00 0
            let n = fmt_u64_hex(e.base, &mut tmp);
            super::generators::append_bytes(buf, &mut pos, &tmp[..n]);
            super::generators::append_bytes(buf, &mut pos, b"-");
            let n = fmt_u64_hex(end, &mut tmp);
            super::generators::append_bytes(buf, &mut pos, &tmp[..n]);
            super::generators::append_bytes(buf, &mut pos, b" ");
            let prot = e.prot;
            let r = if prot & 1 != 0 { b'r' } else { b'-' };
            let w = if prot & 2 != 0 { b'w' } else { b'-' };
            let x = if prot & 4 != 0 { b'x' } else { b'-' };
            super::generators::append_bytes(buf, &mut pos, &[r, w, x, b'p']);
            super::generators::append_bytes(buf, &mut pos, b" 00000000 00:00 0\n");

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
            smaps_emit_kb(buf, &mut pos, b"Swap:", 0); // 0: no swap
            smaps_emit_kb(buf, &mut pos, b"KernelPageSize:", 4);
            smaps_emit_kb(buf, &mut pos, b"MMUPageSize:", 4);
            smaps_emit_kb(buf, &mut pos, b"Locked:", 0);
        }
        pos
    }
}

/// Generate /proc/<pid>/cgroup — single `"0::/\n"` entry for compatibility.
pub(super) unsafe fn proc_gen_cgroup(_pid: u32, buf: &mut [u8]) -> usize {
    const BODY: &[u8] = b"0::/\n";
    let n = BODY.len().min(buf.len());
    buf[..n].copy_from_slice(&BODY[..n]);
    n
}

/// Generate /proc/<pid>/oom_score — placeholder `"0\n"`.
pub(super) unsafe fn proc_gen_oom_score(_pid: u32, buf: &mut [u8]) -> usize {
    const BODY: &[u8] = b"0\n";
    let n = BODY.len().min(buf.len());
    buf[..n].copy_from_slice(&BODY[..n]);
    n
}
