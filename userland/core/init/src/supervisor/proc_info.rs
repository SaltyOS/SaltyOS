// SPDX-License-Identifier: GPL-2.0-only
//
//! `INIT_GET_PROC_INFO` sub-op handler. procfs / sysctlfs / `kill -l`
//! callers ask for snapshots of the proc-table; we pack the relevant
//! fields into the reply `regs[]` — small scalars directly, and larger
//! payloads (argv, `KinfoProc`) paginated across `regs[]` so they never
//! depend on a shared frame the reply does not carry.

use trona_kernel::core_types::TronaMsg;
use trona_kernel::invoke;
use trona_protocol::common::TRONA_OK;
use trona_protocol::init::{
    INIT_ARGV_PAGE_BYTES, INIT_KINFO_PROC_REGS_BASE, KINFO_PROC_COMM_LEN, KinfoProc,
};
use trona_runtime::core::slot_alloc::OwnedCap;

use crate::supervisor::SupervisorState;
use crate::supervisor::proc_table::ProcessRecord;
use crate::wire::{
    GPI_SUB_GET_ARGV, GPI_SUB_GET_EXE_PATH, GPI_SUB_GET_KINFO_PROC, GPI_SUB_GET_KINFO_PROC_PAGE,
    GPI_SUB_GET_PROC_INFO, GPI_SUB_GET_PROC_INFO_FULL, GPI_SUB_GET_PROC_TIMES,
    GPI_SUB_GET_SYSTEM_STATS, GPI_SUB_LIST_PIDS, GPI_SUB_LIST_PIDS_BUF,
};

pub fn handle(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let sub = request.regs[0];
    match sub {
        GPI_SUB_GET_PROC_INFO => get_proc_info(state, request, reply),
        GPI_SUB_GET_PROC_INFO_FULL => get_proc_info_full(state, request, reply),
        GPI_SUB_LIST_PIDS => list_pids(state, reply),
        GPI_SUB_GET_PROC_TIMES => get_proc_times(state, request, reply),
        GPI_SUB_GET_SYSTEM_STATS => get_system_stats(state, reply),
        GPI_SUB_GET_KINFO_PROC => get_kinfo_proc(state, request, reply),
        GPI_SUB_LIST_PIDS_BUF => list_pids_buf(state, request, reply),
        GPI_SUB_GET_ARGV => get_argv(state, request, reply),
        GPI_SUB_GET_EXE_PATH => get_exe_path(state, request, reply),
        GPI_SUB_GET_KINFO_PROC_PAGE => get_kinfo_proc_page(state, request, reply),
        _ => reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64,
    }
    let _ = caller_pid;
}

fn get_proc_info(state: &SupervisorState, request: &TronaMsg, reply: &mut TronaMsg) {
    let pid = request.regs[1] as u32;
    let Some(p) = state.procs.get(pid) else {
        reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
        return;
    };
    reply.label = TRONA_OK;
    reply.length = 7;
    reply.regs[0] = p.pid as u64;
    reply.regs[1] = p.parent_pid as u64;
    reply.regs[2] = p.pgid as u64;
    reply.regs[3] = p.sid as u64;
    reply.regs[4] = p.cred.uid as u64;
    // Reserved. Image format is now detected by the loader from the
    // binary bytes, not stored as manifest/process subsystem state.
    reply.regs[5] = 0;
    reply.regs[6] = p.start_ns;
}

/// `GET_PROC_INFO_FULL` — the layout VFS's `proc_get_info` decodes for
/// `/proc/<pid>/{stat,status,comm}`: ppid/pgid/sid in regs[1..3], the
/// process state discriminant in regs[4], the 32-byte short name packed
/// into regs[5..9], `start_ns` in regs[9], and tty_dev/tty_pgrp in
/// regs[10..11]. Controlling-terminal identity is not tracked per
/// process yet, so the tty fields report 0 (procfs shows no tty).
fn get_proc_info_full(state: &SupervisorState, request: &TronaMsg, reply: &mut TronaMsg) {
    let pid = request.regs[1] as u32;
    let Some(p) = state.procs.get(pid) else {
        reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
        return;
    };
    reply.label = TRONA_OK;
    reply.length = 12;
    reply.regs[0] = p.pid as u64;
    reply.regs[1] = p.parent_pid as u64;
    reply.regs[2] = p.pgid as u64;
    reply.regs[3] = p.sid as u64;
    reply.regs[4] = p.state as u8 as u64;
    let name = p.name.as_bytes();
    let n = name.len().min(32);
    // SAFETY: regs[5..=8] are 32 contiguous bytes inside the register
    // array; `n <= 32`.
    unsafe {
        let dst = (&raw mut reply.regs[5]) as *mut u8;
        core::ptr::copy_nonoverlapping(name.as_ptr(), dst, n);
    }
    reply.regs[9] = p.start_ns;
    reply.regs[10] = 0;
    reply.regs[11] = 0;
}

fn list_pids(state: &SupervisorState, reply: &mut TronaMsg) {
    let mut count = 0u64;
    for p in state.procs.iter_active() {
        if (count as usize) < reply.regs.len() {
            reply.regs[count as usize] = p.pid as u64;
            count += 1;
        }
    }
    reply.label = TRONA_OK;
    reply.length = count;
}

fn get_proc_times(state: &SupervisorState, request: &TronaMsg, reply: &mut TronaMsg) {
    let pid = request.regs[1] as u32;
    let Some(p) = state.procs.get(pid) else {
        reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
        return;
    };
    let (user, sys) = proc_cpu_times(p);
    reply.label = TRONA_OK;
    reply.length = 4;
    reply.regs[0] = user;
    reply.regs[1] = sys;
    // num_threads: init tracks one main TCB per process today; widened
    // to match VFS's `proc_times` decode (`/proc/<pid>/stat` threads col).
    reply.regs[2] = 1;
    reply.regs[3] = p.start_ns;
}

fn get_system_stats(state: &SupervisorState, reply: &mut TronaMsg) {
    // Widened to match VFS's `system_proc_stats` decode (procs_total /
    // procs_running / last_pid) used by `/proc/stat` + `/proc/loadavg`.
    let total = state.procs.count() as u64;
    let running = state
        .procs
        .iter_active()
        .filter(|p| p.state == crate::supervisor::proc_table::ProcessState::Active)
        .count() as u64;
    reply.label = TRONA_OK;
    reply.length = 3;
    reply.regs[0] = total;
    reply.regs[1] = running;
    // last_pid is not tracked yet; 0 placeholder.
    reply.regs[2] = 0;
}

/// User / system CPU time for `p` in nanoseconds: the kernel's live
/// per-TCB accounting while the process runs, falling back to the values
/// stamped at exit once the main TCB is gone.
fn proc_cpu_times(p: &ProcessRecord) -> (u64, u64) {
    let mut user = p.user_cpu_ns;
    let mut sys = p.sys_cpu_ns;
    let main_tcb = p
        .main_tcb
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    if !main_tcb.is_null() {
        if let Some((user_ns, sys_ns)) =
            unsafe { invoke::tcb_get_cpu_times_ctx(trona_runtime::current_ipc_ctx(), main_tcb) }
        {
            user = user_ns;
            sys = sys_ns;
        }
    }
    (user, sys)
}

/// Pack a `KinfoProc` for `p` into `reply.regs[INIT_KINFO_PROC_REGS_BASE..]`,
/// filling only the fields init owns (identity / lifecycle / cred / times).
/// `vm_size` / `vm_rss` / `tty_dev` stay zero — the consumer (vfs) enriches
/// them from mmsrv / pty before emitting the record.
fn fill_kinfo_regs(p: &ProcessRecord, reply: &mut TronaMsg) {
    let mut kp = KinfoProc::zeroed();
    kp.size = core::mem::size_of::<KinfoProc>() as u32;
    kp.pid = p.pid;
    kp.ppid = p.parent_pid;
    kp.pgid = p.pgid;
    kp.sid = p.sid;
    kp.uid = p.cred.uid;
    kp.gid = p.cred.gid;
    kp.euid = p.cred.euid;
    kp.egid = p.cred.egid;
    kp.state = p.state as u8;
    let (user, sys) = proc_cpu_times(p);
    kp.user_time_ns = user;
    kp.system_time_ns = sys;
    kp.start_time_ns = p.start_ns;
    kp.num_threads = 1;
    let name = p.name.as_bytes();
    let n = name.len().min(KINFO_PROC_COMM_LEN);
    kp.comm[..n].copy_from_slice(&name[..n]);
    // SAFETY: regs[INIT_KINFO_PROC_REGS_BASE..] spans size_of::<KinfoProc>()
    // (136 B = 17 words) within the 32-word register array.
    unsafe {
        let dst = (&raw mut reply.regs[INIT_KINFO_PROC_REGS_BASE]) as *mut u8;
        core::ptr::copy_nonoverlapping(
            (&raw const kp) as *const u8,
            dst,
            core::mem::size_of::<KinfoProc>(),
        );
    }
}

/// `GET_KINFO_PROC` — one `KinfoProc` for `regs[1]=pid`, packed into
/// `regs[INIT_KINFO_PROC_REGS_BASE..]` (`regs[0]=1` present marker).
fn get_kinfo_proc(state: &SupervisorState, request: &TronaMsg, reply: &mut TronaMsg) {
    let pid = request.regs[1] as u32;
    let Some(p) = state.procs.get(pid) else {
        reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
        return;
    };
    reply.label = TRONA_OK;
    reply.length = (INIT_KINFO_PROC_REGS_BASE + core::mem::size_of::<KinfoProc>() / 8) as u64;
    reply.regs[0] = 1;
    reply.regs[1] = 0;
    fill_kinfo_regs(p, reply);
}

/// `GET_KINFO_PROC_PAGE` — the `regs[1]=offset`-th active process in
/// init's iteration order, letting a consumer page every process without
/// a separate pid listing. `regs[0]=total`, `regs[1]=1` when a record was
/// written (`0` once `offset >= total`), `KinfoProc` at
/// `regs[INIT_KINFO_PROC_REGS_BASE..]`.
fn get_kinfo_proc_page(state: &SupervisorState, request: &TronaMsg, reply: &mut TronaMsg) {
    let offset = request.regs[1] as usize;
    let total = state.procs.iter_active().count();
    reply.label = TRONA_OK;
    reply.regs[0] = total as u64;
    match state.procs.iter_active().nth(offset) {
        Some(p) => {
            reply.regs[1] = 1;
            fill_kinfo_regs(p, reply);
            reply.length =
                (INIT_KINFO_PROC_REGS_BASE + core::mem::size_of::<KinfoProc>() / 8) as u64;
        }
        None => {
            reply.regs[1] = 0;
            reply.length = 2;
        }
    }
}

fn list_pids_buf(state: &SupervisorState, _request: &TronaMsg, reply: &mut TronaMsg) {
    // Same convention: caller passes shared frame; we write each
    // active pid as a u32, terminated by a 0. For now we only return
    // the count in regs[0].
    let n = state.procs.iter_active().count();
    reply.label = TRONA_OK;
    reply.length = 1;
    reply.regs[0] = n as u64;
}

/// `GET_ARGV` — paginated argv read. `regs[1]` packs
/// `(pid << 32) | byte_offset`. The reply reports
/// `regs[0] = total_argv_bytes`, `regs[1] = bytes_written_this_page`, and
/// packs up to `INIT_ARGV_PAGE_BYTES` argv bytes from `byte_offset` into
/// `regs[2..]` (8 per word, little-endian). argv exceeds a single 256-byte
/// MP record, so the caller pages until it has accumulated `total` bytes;
/// it is never returned in one shot.
fn get_argv(state: &SupervisorState, request: &TronaMsg, reply: &mut TronaMsg) {
    let packed = request.regs[1];
    let pid = (packed >> 32) as u32;
    let offset = (packed & 0xFFFF_FFFF) as usize;
    let Some(p) = state.procs.get(pid) else {
        reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
        return;
    };
    let argv = p.argv.as_bytes();
    let total = argv.len();
    reply.label = TRONA_OK;
    reply.regs[0] = total as u64;
    if offset >= total {
        reply.regs[1] = 0;
        reply.length = 2;
        return;
    }
    let page = (total - offset).min(INIT_ARGV_PAGE_BYTES);
    reply.regs[1] = page as u64;
    let src = &argv[offset..offset + page];
    let mut buf = [0u8; 8];
    for (i, chunk) in src.chunks(8).enumerate() {
        buf[..chunk.len()].copy_from_slice(chunk);
        reply.regs[2 + i] = u64::from_le_bytes(buf);
        buf = [0u8; 8];
    }
    reply.length = (2 + page.div_ceil(8)) as u64;
}

fn get_exe_path(state: &SupervisorState, request: &TronaMsg, reply: &mut TronaMsg) {
    let pid = request.regs[1] as u32;
    let Some(p) = state.procs.get(pid) else {
        reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
        return;
    };
    let bytes = p.exe.as_bytes();
    reply.label = TRONA_OK;
    let words = (bytes.len() + 7) / 8;
    reply.length = (1 + words) as u64;
    reply.regs[0] = bytes.len() as u64;
    let mut buf = [0u8; 8];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        buf[..chunk.len()].copy_from_slice(chunk);
        reply.regs[1 + i] = u64::from_le_bytes(buf);
        buf = [0u8; 8];
    }
}
