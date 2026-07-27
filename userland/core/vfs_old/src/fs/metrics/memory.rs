// SPDX-License-Identifier: GPL-2.0-only
//! System memory statistics. Backed by SYS_SYSMEMINFO (kernel) and mmsrv.

pub(crate) use trona_kernel::core_types::sysinfo::TronaSysMemInfo;
use trona_kernel::core_types::{IpcContext, TronaMsg};
use trona_kernel::ipc;
use trona_protocol::posix::mmsrv::{MM_GET_COMMIT_AS, MM_GET_SYSTEM_MEMINFO};
use uapi::*;

#[inline]
fn ipc_ctx() -> *mut IpcContext {
    crate::ipc_ctx()
}

/// Policy-level memory snapshot from mmsrv `MM_GET_SYSTEM_MEMINFO` (0xA7).
///
/// This carries mmsrv-computed aggregates (commit accounting, writeback
/// counters) that supplement the raw kernel PMM snapshot. Fields are in bytes.
#[derive(Clone, Copy, Default)]
pub(crate) struct PolicySnapshot {
    pub(crate) mem_total_bytes: u64,
    pub(crate) mem_free_bytes: u64,
    pub(crate) mem_used_bytes: u64,
    pub(crate) page_cache_bytes: u64,
    pub(crate) slab_bytes: u64,
    /// Cumulative count of processes SIGKILLed by mmsrv as OOM victims.
    pub(crate) oom_kills_total: u64,
    /// Clean shared file-cache pages that mmsrv can drop and fault back in.
    pub(crate) reclaimable_bytes: u64,
}

/// Committed virtual address space in bytes, from mmsrv `MM_GET_COMMIT_AS`.
pub(crate) fn system_committed_as() -> Result<u64, i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_GET_COMMIT_AS;
        msg.length = 0;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return Err(err as i32);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label as i32);
        }
        Ok(reply.regs[0])
    }
}

/// Query the kernel for a raw PMM page-count snapshot via `SYS_SYSMEMINFO`.
///
/// The kernel writes directly into `out`; VFS always consumes the shared
/// UAPI shape so procfs/sysctlfs cannot drift from the syscall ABI.
pub(crate) fn system_kernel_snapshot() -> Result<TronaSysMemInfo, i32> {
    unsafe {
        let mut snap = TronaSysMemInfo::zeroed();
        let err = trona_kernel::syscall::sys_sysmeminfo(&mut snap as *mut _);
        if err != 0 {
            return Err(err as i32);
        }
        Ok(snap)
    }
}

/// Query mmsrv for a policy-level memory snapshot (`MM_GET_SYSTEM_MEMINFO`).
///
/// The reshaped reply carries: `regs[0]` = mem_total_bytes, `regs[1]` =
/// mem_free_bytes, `regs[2]` = mem_used_bytes, `regs[3]` = page_cache_bytes,
/// `regs[4]` = slab_bytes, `regs[5]` = oom_kills_total (count),
/// `regs[6]` = reclaimable_clean_cache_bytes.
pub(crate) fn system_policy_snapshot() -> Result<PolicySnapshot, i32> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_GET_SYSTEM_MEMINFO;
        msg.length = 0;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return Err(err as i32);
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
