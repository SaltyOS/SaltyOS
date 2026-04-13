// SPDX-License-Identifier: GPL-2.0-only
//! Per-process /proc/<pid>/ file generators.

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::procmgr::*;
use trona::protocol::mmsrv::*;
use trona::types::core::*;

use crate::server::consts::*;
use crate::ipc_ctx;

use super::generators::{fmt_u32, fmt_u64};

/// Query procmgr for list of PIDs. Returns count (up to 19).
pub(super) unsafe fn proc_list_pids(pids: &mut [u32; 19]) -> usize {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_LIST_PIDS;
        msg.length = 0;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona::caps::procmgr_ep(),
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
            trona::caps::procmgr_ep(),
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

pub(super) unsafe fn proc_get_exe_path(pid: u32, exe_path: &mut [u8; MAX_PATH_LEN]) -> Option<usize> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_GET_EXE_PATH;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] proc_get_exe_path pid=");
                _lb.hex(pid as u64);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b"\n");
            });
            return None;
        }

        let path_len = reply.regs[0] as usize;
        if path_len == 0 || path_len > exe_path.len() {
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] proc_get_exe_path pid=");
                _lb.hex(pid as u64);
                _lb.str(b" invalid-len=");
                _lb.hex(path_len as u64);
                _lb.str(b"\n");
            });
            return None;
        }
        let src = &reply.regs[1] as *const u64 as *const u8;
        for i in 0..path_len {
            exe_path[i] = *src.add(i);
        }
        trona::udebug!(|_lb| {
            _lb.str(b"[VFS] proc_get_exe_path pid=");
            _lb.hex(pid as u64);
            _lb.str(b" -> '");
            _lb.bytes(&exe_path[..path_len]);
            _lb.str(b"'\n");
        });
        Some(path_len)
    }
}

/// Query mmsrv for client memory stats. Returns true on success.
pub(super) unsafe fn proc_get_mem_stats(
    pid: u32,
    heap_base: &mut u64,
    heap_current: &mut u64,
    region_count: &mut u64,
    total_pages: &mut u64,
) -> bool {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_GET_CLIENT_STATS;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(ipc_ctx(), trona::caps::mmsrv_ep(), &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return false;
        }
        *heap_base = reply.regs[0];
        *heap_current = reply.regs[1];
        *region_count = reply.regs[2];
        *total_pages = reply.regs[3];
        true
    }
}

/// Generate /proc/<pid>/status content. Returns bytes written.
pub(super) unsafe fn proc_gen_status(pid: u32, buf: *mut u8, buf_size: usize) -> usize {
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

        // Find name length
        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 {
            name_len += 1;
        }
        if name_len == 0 {
            name[0] = b'?';
            name_len = 1;
        }

        let mut pos = 0usize;
        let mut tmp = [0u8; 12];

        // "Name:\t<name>\n"
        let hdr = b"Name:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        for i in 0..name_len {
            if pos < buf_size {
                *buf.add(pos) = name[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        // "State:\t<R/Z/T>\n"
        let hdr = b"State:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
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
            *buf.add(pos) = st_char;
            pos += 1;
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        // "Pid:\t<pid>\n"
        let hdr = b"Pid:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(pid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        // "PPid:\t<ppid>\n"
        let hdr = b"PPid:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(ppid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        // "Pgid:\t<pgid>\n"
        let hdr = b"Pgid:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(pgid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        // "Sid:\t<sid>\n"
        let hdr = b"Sid:\t";
        for b in hdr {
            if pos < buf_size {
                *buf.add(pos) = *b;
                pos += 1;
            }
        }
        let n = fmt_u32(sid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        pos
    }
}

/// Generate /proc/<pid>/stat content (single-line). Returns bytes written.
pub(super) unsafe fn proc_gen_stat(pid: u32, buf: *mut u8, buf_size: usize) -> usize {
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

        let mut pos = 0usize;
        let mut tmp = [0u8; 12];

        // Linux-compatible enough `/proc/<pid>/stat` subset for sudo-rs:
        // "<pid> (<name>) <state> <ppid> <pgid> <sid> <tty_nr> ... <start_time>\n"
        let n = fmt_u32(pid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b' ';
            pos += 1;
        }
        if pos < buf_size {
            *buf.add(pos) = b'(';
            pos += 1;
        }
        for i in 0..name_len {
            if pos < buf_size {
                *buf.add(pos) = name[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b')';
            pos += 1;
        }
        if pos < buf_size {
            *buf.add(pos) = b' ';
            pos += 1;
        }
        let st_char = match state {
            1 => b'R',
            2 => b'Z',
            3 => b'T',
            _ => b'?',
        };
        if pos < buf_size {
            *buf.add(pos) = st_char;
            pos += 1;
        }
        if pos < buf_size {
            *buf.add(pos) = b' ';
            pos += 1;
        }
        let n = fmt_u32(ppid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b' ';
            pos += 1;
        }
        let n = fmt_u32(pgid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b' ';
            pos += 1;
        }
        let n = fmt_u32(sid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *buf.add(pos) = tmp[i];
                pos += 1;
            }
        }
        let ticks_per_sec = 100u64;
        let start_ticks = start_time_ns.saturating_mul(ticks_per_sec) / 1_000_000_000;
        let extra_fields: [u64; 16] = [
            tty_dev,            // tty_nr
            tty_pgrp as u64,    // tpgid
            0, // flags
            0, // minflt
            0, // cminflt
            0, // majflt
            0, // cmajflt
            0, // utime
            0, // stime
            0, // cutime
            0, // cstime
            0, // priority
            0, // nice
            1, // num_threads
            0, // itrealvalue
            start_ticks,
        ];
        for field in extra_fields {
            if pos < buf_size {
                *buf.add(pos) = b' ';
                pos += 1;
            }
            let mut tmp64 = [0u8; 20];
            let n = fmt_u64(field, &mut tmp64);
            for i in 0..n {
                if pos < buf_size {
                    *buf.add(pos) = tmp64[i];
                    pos += 1;
                }
            }
        }
        if pos < buf_size {
            *buf.add(pos) = b'\n';
            pos += 1;
        }

        pos
    }
}
