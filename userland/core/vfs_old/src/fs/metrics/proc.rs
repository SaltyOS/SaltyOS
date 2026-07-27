// SPDX-License-Identifier: GPL-2.0-only
//! Per-process and system-wide process-table snapshots. Backed by procmgr.

use trona_kernel::core_types::kinfo::KinfoProc;
pub(crate) use trona_kernel::core_types::sysinfo::TronaProcMemSnapshot as PerPidMemSnapshot;
use trona_kernel::core_types::{IpcContext, TronaMsg};
use trona_kernel::ipc;
use trona_protocol::posix::procmgr::{
    INIT_GET_ARGV, INIT_GET_CLIENT_VM_STATS, INIT_GET_KINFO_PROC, INIT_GET_PROC_TIMES,
    INIT_GET_SYSTEM_STATS, INIT_LIST_PIDS_BUF,
};
use uapi::*;

/// Largest argv payload we will surface through a single IPC round-trip.
/// Must match procmgr `Process.argv_buf` size. Over-large argv payloads
/// are truncated at the source.
pub(crate) const ARGV_MAX: usize = 512;

/// Owned argv buffer passed back to callers. `len` bytes valid; argv
/// elements are NUL-separated (including a trailing NUL when the source
/// writes one).
#[derive(Clone, Copy)]
pub(crate) struct ArgvBuf {
    pub(crate) bytes: [u8; ARGV_MAX],
    pub(crate) len: u16,
}

impl ArgvBuf {
    pub(crate) const fn zeroed() -> Self {
        ArgvBuf {
            bytes: [0; ARGV_MAX],
            len: 0,
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Per-process CPU time snapshot returned by `INIT_GET_PROC_TIMES`.
/// Runtime fields are in nanoseconds.
#[derive(Clone, Copy, Default)]
pub(crate) struct ProcTimes {
    pub(crate) user_time_ns: u64,
    pub(crate) system_time_ns: u64,
    pub(crate) num_threads: u32,
    pub(crate) start_time_ns: u64,
}

/// System-wide process-table aggregates returned by `INIT_GET_SYSTEM_STATS`.
#[derive(Clone, Copy, Default)]
pub(crate) struct SystemProcStats {
    pub(crate) procs_total: u32,
    pub(crate) procs_running: u32,
    pub(crate) last_pid: u32,
}

#[inline]
fn ipc_ctx() -> *mut IpcContext {
    crate::ipc_ctx()
}

/// Summed per-thread CPU times for `pid`.
pub(crate) fn proc_times(pid: u32) -> Result<ProcTimes, i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_PROC_TIMES;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return Err(err as i32);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label as i32);
        }
        Ok(ProcTimes {
            user_time_ns: reply.regs[0],
            system_time_ns: reply.regs[1],
            num_threads: reply.regs[2] as u32,
            start_time_ns: reply.regs[3],
        })
    }
}

/// Aggregate process-table counts (total / runnable / last pid).
pub(crate) fn system_proc_stats() -> Result<SystemProcStats, i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_SYSTEM_STATS;
        msg.length = 0;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return Err(err as i32);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label as i32);
        }
        Ok(SystemProcStats {
            procs_total: reply.regs[0] as u32,
            procs_running: reply.regs[1] as u32,
            last_pid: reply.regs[2] as u32,
        })
    }
}

/// Read a single `KinfoProc` snapshot for `pid`.
///
/// The caller's IPC buffer `reserved[]` area holds the `KinfoProc` bytes
/// on return; we copy them into a caller-owned struct before the next IPC
/// overwrites the buffer. On a wire shape mismatch (reply `regs[0]` is a
/// different `size`) we still return what procmgr produced — the `size`
/// field inside the struct is the source of truth.
pub(crate) fn kinfo_proc(pid: u32) -> Result<KinfoProc, i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_KINFO_PROC;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return Err(err as i32);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label as i32);
        }
        let ctx = ipc_ctx();
        if (*ctx).ipc_buffer.is_null() {
            return Err(TRONA_INVALID_OPERATION as i32);
        }
        let reserved_ptr = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8;
        let mut kp = KinfoProc::zeroed();
        let copy_len = core::mem::size_of::<KinfoProc>();
        core::ptr::copy_nonoverlapping(reserved_ptr, &raw mut kp as *mut u8, copy_len);
        Ok(kp)
    }
}

/// Paginated pid listing.
///
/// `offset` begins the listing at the Nth pid procmgr currently tracks
/// (procmgr's own iteration order). `out` receives the retrieved pids.
/// Returns `(count_written, total)` so callers can decide whether to
/// paginate further.
pub(crate) fn list_pids(offset: u32, out: &mut [u32]) -> Result<(u32, u32), i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_LIST_PIDS_BUF;
        msg.length = 2;
        msg.regs[0] = offset as u64;
        msg.regs[1] = out.len() as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return Err(err as i32);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label as i32);
        }
        let count = reply.regs[0] as usize;
        let total = reply.regs[1] as u32;
        let ctx = ipc_ctx();
        if (*ctx).ipc_buffer.is_null() {
            return Err(TRONA_INVALID_OPERATION as i32);
        }
        let reserved_ptr = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u32;
        let copy_count = count.min(out.len());
        for i in 0..copy_count {
            out[i] = *reserved_ptr.add(i);
        }
        Ok((copy_count as u32, total))
    }
}

/// Fetch a per-process memory snapshot for `pid` via `INIT_GET_CLIENT_VM_STATS`.
///
/// Procmgr places one `TronaProcMemSnapshot` in the IPC buffer reserved area
/// (same pattern as `INIT_GET_KINFO_PROC`). We copy it out before the next IPC
/// can overwrite the buffer.
pub(crate) fn per_pid_mem_snapshot(pid: u32) -> Result<PerPidMemSnapshot, i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_CLIENT_VM_STATS;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return Err(err as i32);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label as i32);
        }
        let ctx = ipc_ctx();
        if (*ctx).ipc_buffer.is_null() {
            return Err(TRONA_INVALID_OPERATION as i32);
        }
        let reserved_ptr = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8;
        let mut snap = PerPidMemSnapshot::zeroed();
        let produced = if reply.length > 0 && reply.regs[0] != 0 {
            core::cmp::min(
                reply.regs[0] as usize,
                core::mem::size_of::<PerPidMemSnapshot>(),
            )
        } else {
            core::mem::size_of::<PerPidMemSnapshot>()
        };
        core::ptr::copy_nonoverlapping(reserved_ptr, &raw mut snap as *mut u8, produced);
        Ok(snap)
    }
}

/// Fetch `pid`'s NUL-separated argv as procmgr recorded it at spawn/exec.
pub(crate) fn proc_argv(pid: u32) -> Result<ArgvBuf, i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_ARGV;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return Err(err as i32);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label as i32);
        }
        let argv_len = (reply.regs[0] as usize).min(ARGV_MAX);
        let ctx = ipc_ctx();
        if (*ctx).ipc_buffer.is_null() {
            return Err(TRONA_INVALID_OPERATION as i32);
        }
        let reserved_ptr = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8;
        let mut out = ArgvBuf::zeroed();
        core::ptr::copy_nonoverlapping(reserved_ptr, out.bytes.as_mut_ptr(), argv_len);
        out.len = argv_len as u16;
        Ok(out)
    }
}
