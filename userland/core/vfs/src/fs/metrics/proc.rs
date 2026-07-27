// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-process and system-wide process-table snapshots. Backed by
//! init's `INIT_GET_PROC_INFO` sub-op family. All routines route a
//! single `mp_call_ctx` to init and copy the reply payload out of
//! the IPC buffer's `reserved[]` area before the next call can
//! overwrite it.

use trona_kernel::core_types::TronaMsg;
use trona_kernel::ipc::mp_call_ctx;
use trona_protocol::common::TRONA_OK;
pub(crate) use trona_protocol::init::TronaProcMemSnapshot as PerPidMemSnapshot;
use trona_protocol::mm::MM_GET_CLIENT_VM_STATS;

/// Largest argv payload surfaced through a single IPC round-trip.
/// Must match init's `Process.argv_buf` size. Over-large argv
/// payloads are truncated at the source.
pub(crate) const ARGV_MAX: usize = 512;

/// Owned argv buffer passed back to callers. `len` bytes valid;
/// argv elements are NUL-separated (including a trailing NUL when
/// the source writes one).
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

/// Per-process CPU time snapshot returned by
/// `INIT_GET_PROC_INFO_SUB_GET_PROC_TIMES`. Runtime fields are in
/// nanoseconds.
#[derive(Clone, Copy, Default)]
pub(crate) struct ProcTimes {
    pub(crate) user_time_ns: u64,
    pub(crate) system_time_ns: u64,
    pub(crate) num_threads: u32,
    pub(crate) start_time_ns: u64,
}

/// System-wide process-table aggregates returned by
/// `INIT_GET_PROC_INFO_SUB_GET_SYSTEM_STATS`.
#[derive(Clone, Copy, Default)]
pub(crate) struct SystemProcStats {
    pub(crate) procs_total: u32,
    pub(crate) procs_running: u32,
    pub(crate) last_pid: u32,
}

/// Full per-process bookkeeping decoded from a `GET_PROC_INFO_FULL`
/// reply (regs[1..=11]) — mirrors the layout init's
/// `get_proc_info_full` packs. Consumed by the procfs
/// `/proc/<pid>/{comm,stat,status}` formatters.
#[derive(Clone, Copy, Default)]
pub(crate) struct ProcInfoFull {
    pub(crate) ppid: u32,
    pub(crate) pgid: u32,
    pub(crate) sid: u32,
    pub(crate) state: u8,
    pub(crate) name: [u8; 32],
    pub(crate) start_time_ns: u64,
    pub(crate) tty_dev: u64,
    pub(crate) tty_pgrp: u32,
}

impl ProcInfoFull {
    /// Decode a `GET_PROC_INFO_FULL` reply.
    pub(crate) fn from_reply(reply: &TronaMsg) -> Self {
        let mut name = [0u8; 32];
        // SAFETY: regs[5..=8] are 32 contiguous bytes inside the
        // register array.
        unsafe {
            let src = &reply.regs[5] as *const u64 as *const u8;
            core::ptr::copy_nonoverlapping(src, name.as_mut_ptr(), 32);
        }
        Self {
            ppid: reply.regs[1] as u32,
            pgid: reply.regs[2] as u32,
            sid: reply.regs[3] as u32,
            state: reply.regs[4] as u8,
            name,
            start_time_ns: reply.regs[9],
            tty_dev: reply.regs[10],
            tty_pgrp: reply.regs[11] as u32,
        }
    }
}

#[inline]
unsafe fn ipc_ctx() -> *mut trona_kernel::core_types::IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

/// Fetch a per-process memory snapshot for `pid` directly from mmsrv
/// (`MM_GET_CLIENT_VM_STATS`).
///
/// mmsrv owns per-client VSpace + region metadata, so this is queried
/// at its authority with no init hop. The 20-`u64`
/// `TronaProcMemSnapshot` rides back in `reply.regs[0..20]` (one MP
/// record), so there is no `reserved[]` dependency. mmsrv is an
/// always-replying peer (it cannot depend on the vfs reactor), so this
/// synchronous `mp_call` from the owner reactor cannot deadlock.
pub(crate) fn per_pid_mem_snapshot(pid: u32) -> Result<PerPidMemSnapshot, i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_GET_CLIENT_VM_STATS;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = mp_call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(err);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label as i32);
        }
        let mut snap = PerPidMemSnapshot::zeroed();
        // SAFETY: `TronaProcMemSnapshot` is `#[repr(C)]` of 20
        // contiguous `u64`; mmsrv packed them into `reply.regs[0..20]`,
        // and `reply.regs` (`[u64; 32]`) holds at least 20 words.
        ::core::ptr::copy_nonoverlapping(reply.regs.as_ptr(), &raw mut snap as *mut u64, 20);
        Ok(snap)
    }
}
