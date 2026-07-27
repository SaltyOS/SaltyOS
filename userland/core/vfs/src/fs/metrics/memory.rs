// SPDX-License-Identifier: GPL-2.0-only
//
//! System memory statistics. Backed by the `SystemInfo` cap
//! (`KERNITE_INV_SYSINFO_GET_MEMINFO`) for the raw kernel PMM
//! snapshot, and by mmsrv's policy-level aggregate labels
//! (`MM_GET_SYSTEM_MEMINFO`, `MM_GET_COMMIT_AS`).

use trona_kernel::core_types::TronaMsg;
use trona_kernel::ipc::mp_call_ctx;
use trona_protocol::common::TRONA_OK;
pub(crate) use trona_protocol::init::TronaSysMemInfo;
use trona_protocol::mm::{MM_GET_COMMIT_AS, MM_GET_SYSTEM_MEMINFO};

#[inline]
unsafe fn ipc_ctx() -> *mut trona_kernel::core_types::IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

/// Policy-level memory snapshot from mmsrv `MM_GET_SYSTEM_MEMINFO`.
///
/// mmsrv-computed aggregates (commit accounting, writeback
/// counters, reclaim totals) that supplement the raw kernel PMM
/// snapshot. Fields are in bytes.
#[derive(Clone, Copy, Default)]
pub(crate) struct PolicySnapshot {
    pub(crate) mem_total_bytes: u64,
    pub(crate) mem_free_bytes: u64,
    pub(crate) mem_used_bytes: u64,
    pub(crate) page_cache_bytes: u64,
    pub(crate) slab_bytes: u64,
    /// Cumulative count of processes SIGKILLed by mmsrv as OOM
    /// victims.
    pub(crate) oom_kills_total: u64,
    /// Clean shared file-cache pages mmsrv can drop and fault back
    /// in.
    pub(crate) reclaimable_bytes: u64,
}

/// Committed virtual address space in bytes, from mmsrv
/// `MM_GET_COMMIT_AS`.
pub(crate) fn system_committed_as() -> Result<u64, i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_GET_COMMIT_AS;
        msg.length = 0;
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
        Ok(reply.regs[0])
    }
}

/// Query the kernel's `SystemInfo` cap for the raw PMM page-count
/// snapshot via `KERNITE_INV_SYSINFO_GET_MEMINFO`. The kernel
/// writes the `TronaSysMemInfo` shape directly into `out`.
pub(crate) fn system_kernel_snapshot() -> Result<TronaSysMemInfo, i32> {
    let sysinfo = trona_runtime::client::caps::system_info_cap().addr();
    if sysinfo == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }
    let mut snap = TronaSysMemInfo::zeroed();
    let err = trona_kernel::syscall::system_get_meminfo(sysinfo, &raw mut snap);
    if err != 0 {
        return Err(err as i32);
    }
    Ok(snap)
}

/// Query mmsrv for a policy-level memory snapshot
/// (`MM_GET_SYSTEM_MEMINFO`).
///
/// Reply layout: `regs[0]=mem_total_bytes`,
/// `regs[1]=mem_free_bytes`, `regs[2]=mem_used_bytes`,
/// `regs[3]=page_cache_bytes`, `regs[4]=slab_bytes`,
/// `regs[5]=oom_kills_total`, `regs[6]=reclaimable_clean_cache_bytes`.
pub(crate) fn system_policy_snapshot() -> Result<PolicySnapshot, i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_GET_SYSTEM_MEMINFO;
        msg.length = 0;
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
        Ok(PolicySnapshot {
            mem_total_bytes: reply.regs[0],
            mem_free_bytes: reply.regs[1],
            mem_used_bytes: reply.regs[2],
            page_cache_bytes: reply.regs[3],
            slab_bytes: reply.regs[4],
            oom_kills_total: reply.regs[5],
            reclaimable_bytes: reply.regs[6],
        })
    }
}
